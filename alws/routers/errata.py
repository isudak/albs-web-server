from typing import Annotated, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import PlainTextResponse
from fastapi_sqla import AsyncSessionDependency
from sqlalchemy.ext.asyncio import AsyncSession

from alws.auth import get_current_user
from alws.constants import ErrataReleaseStatus
from alws.crud import errata as errata_crud
from alws.dependencies import get_async_db_key
from alws.dramatiq import bulk_errata_release, release_errata
from alws.schemas import errata_schema

router = APIRouter(
    prefix="/errata",
    tags=["errata"],
    dependencies=[Depends(get_current_user)],
)

public_router = APIRouter(
    prefix="/errata",
    tags=["errata"],
)


@router.post("/", response_model=errata_schema.CreateErrataResponse)
async def create_errata_record(
    errata: errata_schema.BaseErrataRecord,
    db: AsyncSession = Depends(AsyncSessionDependency(key=get_async_db_key())),
):
    record = await errata_crud.create_errata_record(
        db,
        errata,
    )
    return {"ok": bool(record)}


@public_router.get("/", response_model=errata_schema.ErrataRecord)
async def get_errata_record(
    errata_id: str,
    errata_platform_id: int,
    db: AsyncSession = Depends(AsyncSessionDependency(key=get_async_db_key())),
):
    errata_record = await errata_crud.get_errata_record(
        db,
        errata_id,
        errata_platform_id,
    )
    if errata_record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unable to find errata record with {errata_id=}",
        )
    return errata_record


@router.get("/get_oval_xml/", response_model=str)
async def get_oval_xml(
    platform_name: str,
    only_released: bool = False,
    db: AsyncSession = Depends(AsyncSessionDependency(key=get_async_db_key())),
):
    records = await errata_crud.get_oval_xml(db, platform_name, only_released)
    if not records:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{platform_name} is not a valid platform",
        )
    return records


@public_router.get("/query/", response_model=errata_schema.ErrataListResponse)
async def list_errata_records(
    pageNumber: Optional[int] = None,
    id: Optional[str] = None,
    ids: Annotated[Optional[List[str]], Query()] = None,
    title: Optional[str] = None,
    platformId: Optional[int] = None,
    cveId: Optional[str] = None,
    status: Optional[ErrataReleaseStatus] = None,
    db: AsyncSession = Depends(AsyncSessionDependency(key=get_async_db_key())),
):
    return await errata_crud.list_errata_records(
        db,
        page=pageNumber,
        errata_id=id,
        errata_ids=ids,
        title=title,
        platform=platformId,
        cve_id=cveId,
        status=status,
    )


@public_router.get(
    "/{record_id}/updateinfo/",
    response_class=PlainTextResponse,
)
async def get_updateinfo_xml(
    record_id: str,
    platform_id: Optional[int] = None,
    db: AsyncSession = Depends(AsyncSessionDependency(get_async_db_key())),
):
    updateinfo_xml = await errata_crud.get_updateinfo_xml_from_pulp(
        db, record_id, platform_id
    )
    if updateinfo_xml is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"Unable to find errata records with {record_id=} and "
                f"{platform_id=} in pulp"
            ),
        )
    return updateinfo_xml


@router.post("/update/", response_model=errata_schema.ErrataRecord)
async def update_errata_record(
    errata: errata_schema.UpdateErrataRequest,
    db: AsyncSession = Depends(AsyncSessionDependency(key=get_async_db_key())),
):
    return await errata_crud.update_errata_record(db, errata)


# TODO: Update this endpoint to include platform_id.
# albs-oval-cacher would need to be updated according to it.
# See https://github.com/AlmaLinux/build-system/issues/207
@router.get("/all/", response_model=List[errata_schema.CompactErrataRecord])
async def list_all_errata_records(
    db: AsyncSession = Depends(AsyncSessionDependency(key=get_async_db_key())),
):
    records = await errata_crud.list_errata_records(db, compact=True)
    return [
        {
            "id": record.id,
            "updated_date": record.updated_date,
        }
        for record in records["records"]
    ]


@router.post(
    "/update_package_status/",
    response_model=errata_schema.ChangeErrataPackageStatusResponse,
)
async def update_package_status(
    packages: List[errata_schema.ChangeErrataPackageStatusRequest],
    db: AsyncSession = Depends(AsyncSessionDependency(key=get_async_db_key())),
):
    try:
        return {
            "ok": bool(await errata_crud.update_package_status(db, packages))
        }
    except ValueError as e:
        return {"ok": False, "error": e.message}


@router.post(
    "/release_record/{record_id}/",
    response_model=errata_schema.ReleaseErrataRecordResponse,
)
async def release_errata_record(
    record_id: str,
    platform_id: int,
    force: bool = False,
    session: AsyncSession = Depends(
        AsyncSessionDependency(key=get_async_db_key())
    ),
):
    db_record = await errata_crud.get_errata_record(
        session,
        record_id,
        platform_id,
    )
    if not db_record:
        return {"message": f"Record {record_id} doesn't exists"}
    if db_record.release_status == ErrataReleaseStatus.IN_PROGRESS:
        return {"message": f"Record {record_id} already in progress"}
    db_record.release_status = ErrataReleaseStatus.IN_PROGRESS
    db_record.last_release_log = None
    await session.flush()
    release_errata.send(record_id, platform_id, force)
    return {
        "message": f"Release updateinfo record {record_id} has been started"
    }


@router.post("/bulk_release_records/")
async def bulk_release_errata_records(records_ids: List[str]):
    bulk_errata_release.send(records_ids)
    return {
        "message": (
            "Following records scheduled for release:"
            f" {', '.join(records_ids)}"
        )
    }


@router.post('/reset-matched-packages')
async def reset_matched_packages(
    record_id: str,
    session: AsyncSession = Depends(
        AsyncSessionDependency(key=get_async_db_key())
    ),
):
    await errata_crud.reset_matched_errata_packages(record_id, session)
    return {'message': f'Packages for record {record_id} have been matched'}
